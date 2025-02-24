#!/usr/local/venv/elf/bin/python3

import logging
import time

import click
import libvirt
import xmltodict

from common.http import tuna
from common.mongo.db import mongodb
from smartx_app.elf.common.utils.libvirt_driver import libvirt_connection
from smartx_app.elf.common.utils import cmd, node_info
from smartx_app.elf.common.resource_wrappers import sriov
from smartx_app.common.node import db


class RetryException(Exception):
    def __init__(self, msg):
        super().__init__(msg)


def _param_precheck(cpu_mode, cpus, vm_json):
    if cpu_mode == "exclusive":
        cpu_list = node_info.decode_cpuset(cpus)
        if len(cpu_list) != vm_json["vcpu"]:
            logging.warning("The number of cpus does not equal to the number of VM vCPU")
            return False

    return True


def _pin_exclusive_vm(**kwargs):
    vm_uuid = kwargs["vm_uuid"]
    cpus = kwargs["cpus"]
    current_step = kwargs["current_step"]
    total_steps = kwargs["total_steps"]

    cpu_list = node_info.decode_cpuset(cpus)
    vcpu_to_pcpu = {i: pcpu for i, pcpu in enumerate(cpu_list)}

    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Going to pin exclusive cpus {cpus}")

    with libvirt_connection() as conn:
        domain = conn.lookupByName(vm_uuid)
        domain_id = domain.ID()
        path = r"/sys/fs/cgroup/cpuset/machine.slice/machine-qemu\x2d{}\x2d{}.scope".format(
            domain_id, vm_uuid.replace("-", r"\x2d")
        )
        for i in range(0, len(vcpu_to_pcpu)):
            vcpu_path = "{}/vcpu{}".format(path, i)
            with open("{}/cpuset.cpus".format(vcpu_path), "w") as f:
                f.writelines(str(vcpu_to_pcpu[i]))

    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Pin exclusive cpus {cpus} succeed")


def _pin_non_exclusive_vm(**kwargs):
    vm_uuid = kwargs["vm_uuid"]
    vm_json = kwargs["vm_json"]
    cpus = kwargs["cpus"]
    current_step = kwargs["current_step"]
    total_steps = kwargs["total_steps"]

    with libvirt_connection() as conn:
        domain = conn.lookupByName(vm_uuid)
        domain_id = domain.ID()
        path = r"/sys/fs/cgroup/cpuset/machine.slice/machine-qemu\x2d{}\x2d{}.scope".format(
            domain_id, vm_uuid.replace("-", r"\x2d")
        )
        for i in range(0, vm_json["vcpu"]):
            vcpu_path = "{}/vcpu{}".format(path, i)
            with open("{}/cpuset.cpus".format(vcpu_path), "w") as f:
                f.writelines(cpus)

    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Pin non-exclusive cpus {cpus} succeed")


def _shutdown_vm(**kwargs):
    vm_uuid = kwargs["vm_uuid"]
    current_step = kwargs["current_step"]
    total_steps = kwargs["total_steps"]
    force_shutdown = kwargs["force_shutdown"]
    vm_json = kwargs["vm_json"]

    with libvirt_connection() as conn:
        domain = conn.lookupByName(vm_uuid)

        if domain.state()[0] == libvirt.VIR_DOMAIN_SHUTOFF:
            logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:VM is already shutoff, skip")
            return

        sriov_handler = sriov.SRIOVHandler(vm_json)
        sriov_handler.release_vfs()
        logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:SR-IOV record released succeed")

        if force_shutdown:
            domain.destroy()
        else:
            domain.shutdown()

        while True:
            domain = conn.lookupByName(vm_uuid)
            domain_state = domain.state()[0]
            if domain_state != libvirt.VIR_DOMAIN_SHUTOFF:
                logging.info(
                    f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:VM is shutting down, current state"
                    f"={domain_state}"
                )
                time.sleep(1)
                continue

            break

    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Shutdown VM succeed")


def _config_numatune(**kwargs):
    vm_uuid = kwargs["vm_uuid"]
    current_step = kwargs["current_step"]
    total_steps = kwargs["total_steps"]
    mem_numa_node = kwargs["mem_numa_node"]

    code, out, error = cmd.execute_cmd(f"virsh numatune {vm_uuid} --nodeset {mem_numa_node} --mode interleave --config")
    logging.info(
        f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Memory binding result: {code},{str(out).strip()},"
        f"{str(error).strip()}"
    )
    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Set memory NUMA node succeed")


def _start_vm(**kwargs):
    vm_uuid = kwargs["vm_uuid"]
    total_steps = kwargs["total_steps"]
    current_step = kwargs["current_step"]

    with libvirt_connection() as conn:
        domain = conn.lookupByName(vm_uuid)
        domain.create()
        while True:
            domain = conn.lookupByName(vm_uuid)
            domain_state = domain.state()[0]
            if domain_state != libvirt.VIR_DOMAIN_RUNNING:
                logging.info(
                    f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:VM is staring, current state={domain_state}"
                )
                time.sleep(1)
                continue

            break

    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Start VM succeed")


def _allocate_sriov(**kwargs):
    vm_uuid = kwargs["vm_uuid"]
    current_step = kwargs["current_step"]
    total_steps = kwargs["total_steps"]
    vm_json = kwargs["vm_json"]

    sriov_handler = sriov.SRIOVHandler(vm_json)
    if not sriov_handler.sriov_nics:
        logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:VM does not have sriov NIC, skip")
        return

    with libvirt_connection() as conn:
        domain = conn.lookupByName(vm_uuid)
        domain_xml_str = domain.XMLDesc()
        domain_xml_dict = xmltodict.parse(domain_xml_str)

        interfaces = domain_xml_dict["domain"]["devices"]["interface"]
        if not isinstance(interfaces, list):
            interfaces = [interfaces]

        interfaces = [x for x in interfaces if x["@type"] != "hostdev"]
        sriov_nics = sriov_handler.allocate_vfs()
        for vf in sriov_nics:
            interfaces.append(vf.domain_json)
        domain_xml_dict["domain"]["devices"]["interface"] = interfaces

        conn.defineXML(xmltodict.unparse(domain_xml_dict))

    result = _check_sriov_nics_allocated(vm_json)
    if not result:
        raise RetryException("SR-IOV assign record not found, may released by cron job")

    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Allocate sriov address succeed")


def _check_sriov_nics_allocated(vm_json):
    tuna_client = tuna.Client()
    vm_node_ip = vm_json["node_ip"]
    vm_host_uuid = db.query_host_by_data_ip(vm_node_ip)["host_uuid"]
    nic_assign_info_list = tuna_client.get_nic_assign_infos(vm_host_uuid)
    nic_assign_info_dict = {}

    for assign_info in nic_assign_info_list:
        if assign_info.get("assign_type") == "sriov":
            for assigned_vf in assign_info.get("assigned_vfs", []):
                sriov_assign_id = sriov._SRIOVAssignID(index=assigned_vf["index"], assign_id=assigned_vf["assign_id"])
                nic_assign_info_dict.setdefault(
                    assign_info["uuid"], {(sriov_assign_id.vm_id, sriov_assign_id.mac_address)}
                ).add((sriov_assign_id.vm_id, sriov_assign_id.mac_address))

    for nic in vm_json.get("nics", []):
        if nic["model"] != "sriov":
            continue

        if nic["pf_id"] not in nic_assign_info_dict:
            return False

        if (vm_json["uuid"], nic["mac_address"]) not in nic_assign_info_dict[nic["pf_id"]]:
            return False

    return True


def _update_virtio_queues(**kwargs):
    vm_uuid = kwargs["vm_uuid"]
    current_step = kwargs["current_step"]
    total_steps = kwargs["total_steps"]
    queues = kwargs.get("queues", 4)  # Default to 4 if not specified

    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Updating virtio queues to {queues}")

    with libvirt_connection() as conn:
        domain = conn.lookupByName(vm_uuid)
        domain_xml_str = domain.XMLDesc()
        domain_xml_dict = xmltodict.parse(domain_xml_str)

        interfaces = domain_xml_dict["domain"]["devices"]["interface"]
        if not isinstance(interfaces, list):
            interfaces = [interfaces]

        # Update queues for virtio interfaces
        for interface in interfaces:
            if interface.get("model", {}).get("@type") == "virtio":
                if "driver" not in interface:
                    interface["driver"] = {}
                if isinstance(interface["driver"], str):
                    interface["driver"] = {"@name": interface["driver"]}
                interface["driver"]["@queues"] = str(queues)

        # Update the domain XML
        conn.defineXML(xmltodict.unparse(domain_xml_dict))

    logging.info(f"[{vm_uuid[0:4]} Step{current_step}/{total_steps}]:Updated virtio queues succeed")


@click.command()
@click.option("--vm_uuid", type=str)
@click.option("--cpu_mode", type=click.Choice(["exclusive", "non_exclusive"], False))
@click.option("--cpus", type=str)
@click.option("--mem_numa_node", type=str)
@click.option("--force_shutdown", type=bool, default=False)
@click.option("--queues", type=int, default=4)  # Add new option for queues
def main(vm_uuid, cpu_mode, cpus, mem_numa_node, force_shutdown, queues):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s  %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('/var/log/zbs/binding.log'),
        ]
    )

    vm_json = mongodb.resources.resource.find_one({"uuid": vm_uuid}, {"_id": 0})
    if not vm_json:
        logging.info(f"VM {vm_uuid} not exists")
        return
    if not _param_precheck(cpu_mode, cpus, vm_json):
        return

    exclusive_vm_steps = [_shutdown_vm, _config_numatune, _allocate_sriov, _start_vm, _pin_exclusive_vm]
    non_exclusive_vm_steps = [_shutdown_vm, _config_numatune, _allocate_sriov, _update_virtio_queues, _start_vm, _pin_non_exclusive_vm]
    #non_exclusive_vm_steps = [_shutdown_vm, _config_numatune, _allocate_sriov, _update_virtio_queues, _start_vm]

    steps = non_exclusive_vm_steps if cpu_mode == "non_exclusive" else exclusive_vm_steps

    arg_dict = {
        "vm_uuid": vm_uuid,
        "cpu_mode": cpu_mode,
        "cpus": cpus,
        "mem_numa_node": mem_numa_node,
        "vm_json": vm_json,
        "force_shutdown": force_shutdown,
        "queues": queues,  # Add queues to arg_dict
    }
    for i, step in enumerate(steps):
        arg_dict.update({"current_step": i + 1, "total_steps": len(steps)})
        while True:
            try:
                step(**arg_dict)
            except RetryException as e:
                logging.info(f"Retry current step because : {str(e)}")
            else:
                break


if __name__ == "__main__":
    main()
