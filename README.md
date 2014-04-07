
### Etherpad Plugin ep_frontend_community


User-Management System for etherpad-lite

This plugin is based mainly on the code of the plugin ep_user_pad_frontend published at https://github.com/aoberegg/ep_user_pad_frontend.

In differenz to the named above plugin, neither public registration nor public pads are allowed. All users need to login.


There are three types of users:
* pad system administrators
* group owners
* normal users

Pad system adminitrators are able to assign new users to the pad system, create (private) groups, and manage users and groups. Group owners are allowed to assigne existing users to to their groups. Normal users are allowed to create pads in their groups and also edit all existing pads of their groups.


#### Download
https://github.com/ckubu/ep_frontend_community/archive/master.zip


#### Install
* Create needed mysql tables and an initial user (PAD System Administrator)
```
CREATE TABLE `GroupPads` (
  `UserID` int(11) DEFAULT '1',
  `GroupID` int(11) NOT NULL,
  `PadName` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`GroupID`,`PadName`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE `Groups` (
  `groupID` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  PRIMARY KEY (`groupID`,`name`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;


CREATE TABLE `NotRegisteredUsersGroups` (
  `email` varchar(255) NOT NULL,
  `groupID` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


CREATE TABLE `User` (
  `userID` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL DEFAULT '',
  `pwd` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  `considered` tinyint(11) DEFAULT NULL,
  `SSO` tinyint(4) DEFAULT NULL,
  `FullName` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  `considerationString` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  `salt` varchar(255) CHARACTER SET utf8 COLLATE utf8_bin DEFAULT NULL,
  `active` int(1) DEFAULT NULL,
  `isAdmin` int(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`userID`,`name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;


CREATE TABLE `UserGroup` (
  `userID` int(11) NOT NULL DEFAULT '0',
  `groupID` int(11) NOT NULL DEFAULT '0',
  `Role` int(11) DEFAULT NULL,
  PRIMARY KEY (`userID`,`groupID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--  Initial User - Pad System Administrator
--
--    User: admin@example.com - Password: admin
--
INSERT INTO `User` 
   VALUES (
      1,'admin@example.com',
      '53e8f649c9bfbccf8f8e2b588d05de8ce26f26228a9cc9340cdc8c5f9b1a0d1e',
      1,0,'Pad System Adminstrator',
      'fGREpQX1cwnUqv3fsqHPkjP3WtlG1ZsXFFx6v0mR','EYEcciC6Nk',1,0
);
```

* Download from git repository into folder "node_modules" of your etherpad-lite installation.
```
# as user of your "etherpad-lite" installation do:
git clone https://github.com/ckubu/ep_frontend_community.git
```

* Install Plugin 
```
cd ep_frontend_community

# as user of your "etherpad-lite" installation do:
npm install

# Restart etherpad-lite (i.e debian installation: as root user do:)
service etherpad-lite restart
```
* Adjust email.json to your needs
* Maybe you want replace `static/images/logo.png` with your logo

Now you can login with credentials:
```
   username......: admin@example.com
   password......: admin
```


#### Create a Plugin
See https://github.com/ether/etherpad-lite/wiki/Creating-a-plugin  [Step 5 Install plugin])
