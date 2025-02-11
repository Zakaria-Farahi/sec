---
title: OSCP Active Directory Introduction and Enumeration
published: 2025-01-21
description: 'Active Directory Introduction and Enumeration Notes for OSCP'
image: './img/cover.png'
tags: [OSCP, Notes, Course]
category: 'Notes'
draft: true 
---

# 1. Active Directory - Introduction

when a user attempts to log in to the domain, a request is sent to a Domain Controller (DC), which checks whether or not the user is allowed to log in to the domain. One or more DCs act as the hub and core of the domain, storing all OUs, objects, and their attributes.

:::important
Members of Domain Admins are among the most privileged objects in the domain. If an attacker compromises a member of this group (often referred to as domain administrators), they essentially gain complete control over the domain.

members of the Enterprise Admins group are granted full control over all the domains in the forest and have Administrator privilege on all DCs.
:::

## 1.1. Enumeration - Defining our Goals

we will perform the enumeration from one client machine with the low privileged stephanie domain user. However, once we start performing attacks and we are able to gain access to additional users and computers, we may have to repeat parts of the enumeration process from the new standpoint.

# 2. Active Directory - Manual Enumeration
## 2.1. Active Directory - Enumeration Using Legacy Windows Tools

Connecting to the Windows 11 client using "xfreerdp"
```bash
xfreerdp /u:stephanie /d:corp.com /v:192.168.50.75
```

