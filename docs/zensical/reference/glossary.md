<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Glossary

This page defines terms that IRIS uses with a specific meaning, one entry per term.

## staging, to stage

Staging means copying an image to the device's flash and checking its hash,
then stopping. The device keeps running its current software until you
install the image yourself. See the [Overview](../index.md).

## instruction

The signed message the server sends a device saying which images to stage
and how. See [Security model](../architecture/security-model.md).

## envelope

The encrypted file that carries an instruction. See
[Security model](../architecture/security-model.md).

## tick

One pass of the agent's check-in loop. See
[How an image reaches a device](../architecture/data-path.md).

## LKG

The last policy the device accepted (last known good). See
[Security model](../architecture/security-model.md).

## keyed state

The files the server keeps per device, under that device's id. See
[Data formats and states](state-and-data.md).

## mutual origin

Two devices that both hold a full copy of the same image. See
[Security model](../architecture/security-model.md).

## quarantine (image)

An image that failed the Cisco hash check and is held back from devices. See
[Publish and verify images](../user-guide/images.md).

## quarantine (device)

A device told to stop sharing with every peer. See
[Control peer sharing](../user-guide/roles.md).

## principal

Who a request is from: a device, the server's seeder, or a legacy device. See
[Security model](../architecture/security-model.md).

## peer policy, sharing policy

The rules that say which devices may share pieces with which. See
[Security model](../architecture/security-model.md).

## role

A named group of devices that share with each other. See
[Control peer sharing](../user-guide/roles.md).

## management type

How the agent reaches the network: on its own address, on your management
VLAN, or through the router. See [Management types](../install/management-types.md).

## wave

A group of devices a schedule releases together. See
[Schedule maintenance windows](../user-guide/scheduling.md).

## scheduled outcome

The record of what a scheduled run did on one device (the API calls it a receipt). See [Schedule maintenance windows](../user-guide/scheduling.md).

## origin seeder

The server's own copy of the image, the first source in the swarm. See
[Limits](../architecture/limitations.md).

## park

Keep an unassigned image on the device in case it is assigned again. See
[Assign images and check status](../user-guide/assignments.md).

## verifier_missing

The device's agent package carries a bundled signature verifier, so it checks every instruction. `verifier_missing` means the installed package is outdated or damaged; redeploy the agent package to restore checking.
See [Troubleshoot](../user-guide/troubleshooting.md).

## Bulk Hash

The checksum Cisco publishes for an image. See
[Publish and verify images](../user-guide/images.md).

## root key, signing root

One of the two offline keys that sign every instruction key. See
[Create the signing keys](../install/signing-roots.md).
