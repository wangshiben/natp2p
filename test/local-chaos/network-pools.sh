#!/usr/bin/env bash

select_topology_network_octets() {
  local used_octets=" " subnet candidate
  local control_octet=${BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET:-}
  local access_octet=${BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET:-}
  local network_ids=()
  mapfile -t network_ids < <(docker network ls -q 2>/dev/null)
  if ((${#network_ids[@]} > 0)); then
    while IFS= read -r subnet; do
      if [[ $subnet =~ ^10\.([0-9]{1,3})\. ]]; then
        used_octets+="${BASH_REMATCH[1]} "
      fi
    done < <(docker network inspect --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' "${network_ids[@]}" 2>/dev/null)
  fi

  for candidate in {204..223}; do
    [[ $used_octets == *" $candidate "* ]] && continue
    [[ $candidate == "$control_octet" || $candidate == "$access_octet" ]] && continue
    if [[ -z $control_octet ]]; then
      control_octet=$candidate
    elif [[ -z $access_octet ]]; then
      access_octet=$candidate
    fi
    [[ -n $control_octet && -n $access_octet ]] && break
  done
  if [[ -z $control_octet || -z $access_octet ]]; then
    printf '[local-chaos] 无法选择两个空闲的 Docker /16 地址池\n' >&2
    return 1
  fi
  BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET=$control_octet
  BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET=$access_octet
  export BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET
  printf '[local-chaos] 使用隔离地址池 control=10.%s.0.0/16 access=10.%s.0.0/16\n' \
    "$BNFS_CHAOS_CONTROL_NETWORK_SECOND_OCTET" "$BNFS_CHAOS_ACCESS_NETWORK_SECOND_OCTET"
}
