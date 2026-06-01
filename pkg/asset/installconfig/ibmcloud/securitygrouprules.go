package ibmcloud

import (
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"k8s.io/utils/ptr"
)

// HasTCPIngressRule reports whether rules contains an inbound TCP rule that
// allows the exact single destination port from the given remote CIDR.
func HasTCPIngressRule(rules []vpcv1.SecurityGroupRuleIntf, port int64, cidr string) bool {
	for _, r := range rules {
		tcp, ok := r.(*vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudp)
		if !ok {
			continue
		}
		if tcp.Direction == nil || *tcp.Direction != vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudpDirectionInboundConst {
			continue
		}
		if tcp.Protocol == nil || *tcp.Protocol != vpcv1.SecurityGroupRuleSecurityGroupRuleProtocolTcpudpProtocolTCPConst {
			continue
		}
		if tcp.PortMin == nil || tcp.PortMax == nil || *tcp.PortMin != port || *tcp.PortMax != port {
			continue
		}
		remote, ok := tcp.Remote.(*vpcv1.SecurityGroupRuleRemoteCIDR)
		if !ok || remote.CIDRBlock == nil || *remote.CIDRBlock != cidr {
			continue
		}
		return true
	}
	return false
}

// NewTCPIngressRulePrototype builds a security group rule prototype that allows
// inbound TCP traffic on a single destination port from the given remote CIDR.
func NewTCPIngressRulePrototype(port int64, cidr string) vpcv1.SecurityGroupRulePrototypeIntf {
	return &vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolTcpudp{
		Direction: ptr.To(vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolTcpudpDirectionInboundConst),
		Protocol:  ptr.To(vpcv1.SecurityGroupRulePrototypeSecurityGroupRuleProtocolTcpudpProtocolTCPConst),
		PortMin:   ptr.To(port),
		PortMax:   ptr.To(port),
		Remote: &vpcv1.SecurityGroupRuleRemotePrototypeCIDR{
			CIDRBlock: ptr.To(cidr),
		},
	}
}
