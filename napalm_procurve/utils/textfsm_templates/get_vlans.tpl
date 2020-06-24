Value Required vlan_id (\d+)
Value vlan_name ([^"]+)
Value untagged_vlan_list ([,\-\d]+)
Value tagged_vlan_list ([,\-\d]+)

Start
  ^vlan ${vlan_id}
  ^\s+name "${vlan_name}"
  ^\s+untagged ${untagged_vlan_list}
  ^\s+tagged ${tagged_vlan_list}
  ^\s+exit -> Record

