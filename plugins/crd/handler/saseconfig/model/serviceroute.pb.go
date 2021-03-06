// Code generated by protoc-gen-go. DO NOT EDIT.
// source: serviceroute.proto

package model

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// ServiceRoute is used to store definition for a Sase Service Route
type ServiceRoute struct {
	// Sase Service Instance Name
	ServiceInstanceName string `protobuf:"bytes,1,opt,name=service_instance_name,json=serviceInstanceName,proto3" json:"service_instance_name,omitempty"`
	// Route network scope
	RouteNetworkScope string `protobuf:"bytes,2,opt,name=route_network_scope,json=routeNetworkScope,proto3" json:"route_network_scope,omitempty"`
	// Destination Network
	DestinationNetwork string `protobuf:"bytes,3,opt,name=destination_network,json=destinationNetwork,proto3" json:"destination_network,omitempty"`
	// Gateway IP Address
	GatewayAddress string `protobuf:"bytes,4,opt,name=gateway_address,json=gatewayAddress,proto3" json:"gateway_address,omitempty"`
	// Gateway service ID
	GatewayServiceId string `protobuf:"bytes,5,opt,name=gateway_service_id,json=gatewayServiceId,proto3" json:"gateway_service_id,omitempty"`
	// Gateway network. Identifies VRF
	GatewayNetworkScope string `protobuf:"bytes,6,opt,name=gateway_network_scope,json=gatewayNetworkScope,proto3" json:"gateway_network_scope,omitempty"`
	// egress interface
	EgressInterface      string   `protobuf:"bytes,7,opt,name=egress_interface,json=egressInterface,proto3" json:"egress_interface,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ServiceRoute) Reset()         { *m = ServiceRoute{} }
func (m *ServiceRoute) String() string { return proto.CompactTextString(m) }
func (*ServiceRoute) ProtoMessage()    {}
func (*ServiceRoute) Descriptor() ([]byte, []int) {
	return fileDescriptor_b4d8730375bccbc6, []int{0}
}

func (m *ServiceRoute) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ServiceRoute.Unmarshal(m, b)
}
func (m *ServiceRoute) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ServiceRoute.Marshal(b, m, deterministic)
}
func (m *ServiceRoute) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ServiceRoute.Merge(m, src)
}
func (m *ServiceRoute) XXX_Size() int {
	return xxx_messageInfo_ServiceRoute.Size(m)
}
func (m *ServiceRoute) XXX_DiscardUnknown() {
	xxx_messageInfo_ServiceRoute.DiscardUnknown(m)
}

var xxx_messageInfo_ServiceRoute proto.InternalMessageInfo

func (m *ServiceRoute) GetServiceInstanceName() string {
	if m != nil {
		return m.ServiceInstanceName
	}
	return ""
}

func (m *ServiceRoute) GetRouteNetworkScope() string {
	if m != nil {
		return m.RouteNetworkScope
	}
	return ""
}

func (m *ServiceRoute) GetDestinationNetwork() string {
	if m != nil {
		return m.DestinationNetwork
	}
	return ""
}

func (m *ServiceRoute) GetGatewayAddress() string {
	if m != nil {
		return m.GatewayAddress
	}
	return ""
}

func (m *ServiceRoute) GetGatewayServiceId() string {
	if m != nil {
		return m.GatewayServiceId
	}
	return ""
}

func (m *ServiceRoute) GetGatewayNetworkScope() string {
	if m != nil {
		return m.GatewayNetworkScope
	}
	return ""
}

func (m *ServiceRoute) GetEgressInterface() string {
	if m != nil {
		return m.EgressInterface
	}
	return ""
}

func init() {
	proto.RegisterType((*ServiceRoute)(nil), "model.ServiceRoute")
}

func init() {
	proto.RegisterFile("serviceroute.proto", fileDescriptor_b4d8730375bccbc6)
}

var fileDescriptor_b4d8730375bccbc6 = []byte{
	// 240 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x54, 0x90, 0xc1, 0x4a, 0x03, 0x31,
	0x10, 0x86, 0x69, 0xb5, 0x15, 0x83, 0xd8, 0x3a, 0x8b, 0x90, 0xa3, 0x78, 0x51, 0x41, 0x2a, 0xe8,
	0x13, 0x78, 0xdc, 0x4b, 0x0f, 0xed, 0x03, 0x84, 0xb8, 0x19, 0x4b, 0xd0, 0x4d, 0x4a, 0x32, 0x5a,
	0x7c, 0x54, 0xdf, 0x46, 0x76, 0x32, 0x91, 0xee, 0xf5, 0xff, 0xbe, 0x7f, 0x77, 0xfe, 0x28, 0xc8,
	0x98, 0xbe, 0x7d, 0x87, 0x29, 0x7e, 0x11, 0xae, 0xf6, 0x29, 0x52, 0x84, 0x59, 0x1f, 0x1d, 0x7e,
	0xde, 0xfe, 0x4e, 0xd5, 0xc5, 0xb6, 0xd0, 0xcd, 0x40, 0xe1, 0x59, 0x5d, 0x8b, 0x6d, 0x7c, 0xc8,
	0x64, 0x43, 0x87, 0x26, 0xd8, 0x1e, 0xf5, 0xe4, 0x66, 0x72, 0x7f, 0xbe, 0x69, 0x04, 0xb6, 0xc2,
	0xd6, 0xb6, 0x47, 0x58, 0xa9, 0x86, 0x3f, 0x6d, 0x02, 0xd2, 0x21, 0xa6, 0x0f, 0x93, 0xbb, 0xb8,
	0x47, 0x3d, 0xe5, 0xc6, 0x15, 0xa3, 0x75, 0x21, 0xdb, 0x01, 0xc0, 0x93, 0x6a, 0x1c, 0x66, 0xf2,
	0xc1, 0x92, 0x8f, 0xa1, 0xb6, 0xf4, 0x09, 0xfb, 0x70, 0x84, 0xa4, 0x05, 0x77, 0x6a, 0xb1, 0xb3,
	0x84, 0x07, 0xfb, 0x63, 0xac, 0x73, 0x09, 0x73, 0xd6, 0xa7, 0x2c, 0x5f, 0x4a, 0xfc, 0x5a, 0x52,
	0x78, 0x54, 0x50, 0xc5, 0xff, 0x15, 0x4e, 0xcf, 0xd8, 0x5d, 0x0a, 0x91, 0xb9, 0xad, 0x1b, 0xb6,
	0x56, 0x7b, 0x7c, 0xf9, 0xbc, 0x6c, 0x15, 0x38, 0xba, 0xfd, 0x41, 0x2d, 0x71, 0x37, 0xfc, 0xcb,
	0xf8, 0x40, 0x98, 0xde, 0x6d, 0x87, 0xfa, 0x8c, 0xf5, 0x45, 0xc9, 0xdb, 0x1a, 0xbf, 0xcd, 0xf9,
	0xa5, 0x5f, 0xfe, 0x02, 0x00, 0x00, 0xff, 0xff, 0xc8, 0xba, 0x99, 0x36, 0x7f, 0x01, 0x00, 0x00,
}
