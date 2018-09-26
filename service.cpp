// This file is a part of the IncludeOS unikernel - www.includeos.org
//
// Copyright 2015 Oslo and Akershus University College of Applied Sciences
// and Alfred Bratterud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <service>
#include <statman>
#include <iostream>
#include <net/inet>
#include <net/super_stack.hpp>
#include <net/nat/napt.hpp>
#include <net/router.hpp>

using namespace net;

std::unique_ptr<Router<IP4>> router;
std::shared_ptr<Conntrack> ct;
std::unique_ptr<nat::NAPT> natty;

Filter_verdict<IP4> iperf_snat(IP4::IP_packet_ptr pckt, Inet&, Conntrack::Entry_ptr ct_entry)
{
  if (not ct_entry) {
    return {nullptr, Filter_verdict_type::DROP};
  }
  if (pckt->ip_protocol() == Protocol::TCP) {
    auto& tcp_pckt = static_cast<tcp::Packet&>(*pckt);

    if ((tcp_pckt.dst_port() == 5201 or tcp_pckt.dst_port() == 5202
      or tcp_pckt.dst_port() == 5203 or tcp_pckt.dst_port() == 5204
      or tcp_pckt.dst_port() == 5205 or tcp_pckt.dst_port() == 5206
      or tcp_pckt.dst_port() == 5207 or tcp_pckt.dst_port() == 5208))
    {
      natty->snat(*pckt, ct_entry, IP4::addr{10,0,1,10});
    }
  }

  return {std::move(pckt), Filter_verdict_type::ACCEPT};
}

Filter_verdict<IP4> iperf_dnat(IP4::IP_packet_ptr pckt, Inet&, Conntrack::Entry_ptr ct_entry)
{
  if (not ct_entry) {
    return {nullptr, Filter_verdict_type::DROP};
  }
  if (pckt->ip_protocol() == Protocol::TCP) {
    auto& tcp_pckt = static_cast<tcp::Packet&>(*pckt);

    if ((tcp_pckt.dst_port() == 5201 or tcp_pckt.dst_port() == 5202
      or tcp_pckt.dst_port() == 5203 or tcp_pckt.dst_port() == 5204
      or tcp_pckt.dst_port() == 5205 or tcp_pckt.dst_port() == 5206
      or tcp_pckt.dst_port() == 5207 or tcp_pckt.dst_port() == 5208))
    {
      natty->dnat(*pckt, ct_entry, IP4::addr{10,0,1,1});
    }
  }
  return {std::move(pckt), Filter_verdict_type::ACCEPT};
}

void Service::start(const std::string&)
{
  static auto& out = Super_stack::get(0);
  static auto& in1 = Super_stack::get(1);
  static auto& in2 = Super_stack::get(2);
  static auto& in3 = Super_stack::get(3);
  static auto& in4 = Super_stack::get(4);
  static auto& in5 = Super_stack::get(5);
  static auto& in6 = Super_stack::get(6);
  static auto& in7 = Super_stack::get(7);
  static auto& in8 = Super_stack::get(8);

  ct = std::make_shared<Conntrack>();
  out.enable_conntrack(ct);
  in1.enable_conntrack(ct);
  in2.enable_conntrack(ct);
  in3.enable_conntrack(ct);
  in4.enable_conntrack(ct);
  in5.enable_conntrack(ct);
  in6.enable_conntrack(ct);
  in7.enable_conntrack(ct);
  in8.enable_conntrack(ct);

  // NAT
  natty = std::make_unique<nat::NAPT>(ct);

  auto snat_translate = [](IP4::IP_packet_ptr pckt, Inet&, Conntrack::Entry_ptr entry)-> auto {
    natty->snat(*pckt, entry);
    return Filter_verdict<IP4>{std::move(pckt), Filter_verdict_type::ACCEPT};
  };
  auto dnat_translate = [](IP4::IP_packet_ptr pckt, Inet&, Conntrack::Entry_ptr entry)-> auto {
    natty->dnat(*pckt, entry);
    return Filter_verdict<IP4>{std::move(pckt), Filter_verdict_type::ACCEPT};
  };

  in8.ip_obj().prerouting_chain().chain.push_back(iperf_dnat);
  in4.ip_obj().prerouting_chain().chain.push_back(iperf_dnat);
  in5.ip_obj().prerouting_chain().chain.push_back(iperf_dnat);
  in6.ip_obj().prerouting_chain().chain.push_back(iperf_dnat);
  in7.ip_obj().prerouting_chain().chain.push_back(iperf_dnat);
  in1.ip_obj().prerouting_chain().chain.push_back(iperf_dnat);
  in2.ip_obj().prerouting_chain().chain.push_back(iperf_dnat);
  in3.ip_obj().prerouting_chain().chain.push_back(iperf_dnat);
  out.ip_obj().postrouting_chain().chain.push_back(iperf_snat);

  in8.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  in8.ip_obj().postrouting_chain().chain.push_back(snat_translate);
  in4.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  in4.ip_obj().postrouting_chain().chain.push_back(snat_translate);
  in5.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  in5.ip_obj().postrouting_chain().chain.push_back(snat_translate);
  in6.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  in6.ip_obj().postrouting_chain().chain.push_back(snat_translate);
  in7.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  in7.ip_obj().postrouting_chain().chain.push_back(snat_translate);
  in1.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  in1.ip_obj().postrouting_chain().chain.push_back(snat_translate);
  in2.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  in2.ip_obj().postrouting_chain().chain.push_back(snat_translate);
  in3.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  in3.ip_obj().postrouting_chain().chain.push_back(snat_translate);
  out.ip_obj().prerouting_chain().chain.push_back(dnat_translate);
  out.ip_obj().postrouting_chain().chain.push_back(snat_translate);

  // Router
  Router<IP4>::Routing_table routing_table {
    { IP4::addr{10,0,1,0}, IP4::addr{255,255,255,0}, 0, out, 1 },
    { IP4::addr{10,0,0,101}, IP4::addr{255,255,255,255}, 0, in1, 1 },
    { IP4::addr{10,0,0,102}, IP4::addr{255,255,255,255}, 0, in2, 1 },
    { IP4::addr{10,0,0,103}, IP4::addr{255,255,255,255}, 0, in3, 1 },
    { IP4::addr{10,0,0,104}, IP4::addr{255,255,255,255}, 0, in4, 1 },
    { IP4::addr{10,0,0,105}, IP4::addr{255,255,255,255}, 0, in5, 1 },
    { IP4::addr{10,0,0,106}, IP4::addr{255,255,255,255}, 0, in6, 1 },
    { IP4::addr{10,0,0,107}, IP4::addr{255,255,255,255}, 0, in7, 1 },
    { IP4::addr{10,0,0,108}, IP4::addr{255,255,255,255}, 0, in8, 1 }
  };
  router = std::make_unique<Router<IP4>>(routing_table);

  out.set_forward_delg(router->forward_delg());
  in1.set_forward_delg(router->forward_delg());
  in2.set_forward_delg(router->forward_delg());
  in3.set_forward_delg(router->forward_delg());
  in4.set_forward_delg(router->forward_delg());
  in5.set_forward_delg(router->forward_delg());
  in6.set_forward_delg(router->forward_delg());
  in7.set_forward_delg(router->forward_delg());
  in8.set_forward_delg(router->forward_delg());

  auto forward_hack = [](IP4::IP_packet_ptr pckt, Inet& inet, Conntrack::Entry_ptr entry)-> auto
  {
    static const auto dest = ip4::Addr{10,0,0,1};
    if (pckt->ip_protocol() == Protocol::TCP and pckt->ip_dst() == ip4::Addr{10,0,0,1} and &inet == &out)
    {
      auto& tcp_pckt = static_cast<tcp::Packet&>(*pckt);

      if (tcp_pckt.src_port() == 5201)
        in1.ip_obj().ship(std::move(pckt), dest, entry);
      else if (tcp_pckt.src_port() == 5202)
        in2.ip_obj().ship(std::move(pckt), dest, entry);
      else if (tcp_pckt.src_port() == 5203)
        in3.ip_obj().ship(std::move(pckt), dest, entry);
      else if (tcp_pckt.src_port() == 5204)
        in4.ip_obj().ship(std::move(pckt), dest, entry);
      else if (tcp_pckt.src_port() == 5205)
        in5.ip_obj().ship(std::move(pckt), dest, entry);
      else if (tcp_pckt.src_port() == 5206)
        in6.ip_obj().ship(std::move(pckt), dest, entry);
      else if (tcp_pckt.src_port() == 5207)
        in7.ip_obj().ship(std::move(pckt), dest, entry);
      else if (tcp_pckt.src_port() == 5208)
        in8.ip_obj().ship(std::move(pckt), dest, entry);

      return Filter_verdict<IP4>{nullptr, Filter_verdict_type::DROP};
    }

    return Filter_verdict<IP4>{std::move(pckt), Filter_verdict_type::ACCEPT};
  };

  router->forward_chain.chain.push_back(forward_hack);

  using namespace std::chrono;
  Timers::periodic(3s, 3s, [](auto) {
    auto eth0_rx  = Statman::get().get_by_name("eth0.ethernet.packets_rx").get_uint64();
    auto eth0_tx  = Statman::get().get_by_name("eth0.ethernet.packets_tx").get_uint64();
    auto eth1_rx  = Statman::get().get_by_name("eth1.ethernet.packets_rx").get_uint64();
    auto eth1_tx  = Statman::get().get_by_name("eth1.ethernet.packets_tx").get_uint64();
    printf("ETH0: rx=%zu tx=%zu ETH1: rx=%zu tx=%zu\n",
      eth0_rx, eth0_tx, eth1_rx, eth1_tx);
  });
}
