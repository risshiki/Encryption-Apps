import rbac.acl

acl = rbac.acl.Registry()
acl.add_role("member")
acl.add_role("car", ["member"])
acl.add_role("primarycar", ["member"])
acl.add_role("newcar", ["external"])

acl.add_resource("list")
acl.allow("member", "view", "list")
acl.allow("car", "view", "list")
acl.allow("primarycar", "modify", "list")

acl.deny("car", "modify", "list")
acl.deny("newcar", "modify", "list")



if acl.is_allowed("primarycar", "modify", "list"):
    print("Primary Car should modify list")
    #You can transfer control here 
else:
    
    #You can transfer control here 
    print("Car should not modify list")

if acl.is_allowed("car", "modify", "list"):
    print("Car should modify list")
    #You can transfer control here
else:
    
    #You can transfer control here
    print("Car should modify list")
