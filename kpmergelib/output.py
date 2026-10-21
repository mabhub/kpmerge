"""Building the reduced XML document to import into a temporary database."""
import base64
import copy
import uuid
import xml.etree.ElementTree as ET

from . import xmltree

_ZERO_UUID = "AAAAAAAAAAAAAAAAAAAAAA=="


def _new_uuid() -> str:
    return base64.b64encode(uuid.uuid4().bytes).decode()


def renew_uuids(group: ET.Element) -> None:
    """New UUIDs for all groups and entries of the subtree (modifies `group`).

    A history version keeps its entry's UUID.
    """
    group.find("UUID").text = _new_uuid()
    for node in group.findall("LastTopVisibleEntry"):
        node.text = _ZERO_UUID
    for entry in group.findall("Entry"):
        new = _new_uuid()
        entry.find("UUID").text = new
        for version in entry.findall("History/Entry"):
            version.find("UUID").text = new
    for sub in group.findall("Group"):
        renew_uuids(sub)


def build_import_document(doc: ET.Element, dest_parent_path: str, dest_name: str,
                          merged: ET.Element) -> bytes:
    """Document holding only the destination's ancestor chain and the merged group."""
    new = copy.deepcopy(doc)
    chain = xmltree.group_chain(new, dest_parent_path)
    for i, group in enumerate(chain):
        keep = chain[i + 1] if i + 1 < len(chain) else None
        for child in list(group):
            if child.tag == "Entry" or (child.tag == "Group" and child is not keep):
                group.remove(child)

    fresh = copy.deepcopy(merged)
    fresh.tail = None
    fresh.find("Name").text = dest_name
    renew_uuids(fresh)
    chain[-1].append(fresh)

    deleted = new.find("Root/DeletedObjects")
    if deleted is not None:
        for child in list(deleted):
            deleted.remove(child)
    return ET.tostring(new, encoding="utf-8", xml_declaration=True)
