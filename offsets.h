#pragma once

#define object_manager 0x156C698 

/*Dictionary Offsets*/

#define off_dic_entries 0x18
#define off_disc_count 0x40

/*Generic List*/

#define off_generic_count 0x18
#define off_generic_base 0x10

/*  offset::array::base */

#define off_base 0x20

/*Player Offsets*/

#define off_player_profile 0x440
#define off_player_body 0xA8
#define off_movement_context 0x40
#define off_health_controller 0x470
#define off_procedural_weapon_anim 0x190
#define off_player_physical 0x450
#define off_handscontroller 0x488

#define sekeleton_root_joint 0x28


/*EFT.Profile*/

#define off_profileID 0x10
#define off_accountID 0x18
#define off_profileinfo 0x28

/*EFT.Profie.Info*/

#define off_nickname 0x10
#define off_groupid 0x18
#define off_side 0x50

/*Physical Offsets*/

#define off_stamina 0x28
#define off_hands_stamina 0x30
#define off_oxygen 0x38

/* [Class] .ProceduralWeaponAnimation */

#define off_breatheffector 0x28
#define off_walkeffector 0x30
#define off_shoteffector 0x48
#define off_mask 0xF8
#define off_shotdirection 0x1CC
#define off_cameratarget 0x160

/* -.ShotEffector*/

#define off_recoil_strength_xy 0x38
#define off_recoil_strength_z 0x40


/* ThermalVision*/

#define off_ison 0xD0
#define off_IsNoisy 0xD1
#define off_isfpsstuck 0xD2
#define off_ismotionblurred 0xD3
#define off_IsGlitch 0xD4
#define off_IsPixelated 0xD5

/* VisorEffect */

#define off_Intensity 0xB8
#define off_Velocity 0x108

/* EFT.Interactive.ExfiltrationPoint */

#define off_exitsettings 0x58


/*AIFirearmController*/

#define off_fireport 0xE8
#define off_isAiming 0x145
#define off_weaponlength 0x14C

/* Diz.Skinning.Skeleton*/

#define off_skeleton_keys 0x20
#define off_skeleton_values 0x28

/*Camera Offsets*/

#define off_viewmatrix 0x00D8


/*Game Object Manager Offsets*/

#define lastTaggedObject 0x0000
#define taggedObjects 0x0008
#define lastActiveObject 0x0010
#define activeObjects 0x0018

#define nextObjectLink 0x0008

/*Movement Context*/
#define off_angles_0 0x1F8
#define off_angle_1 0x200
#define off_position 0x208

/*Health*/

#define off_health_max 0x14
#define off_health_current 0x10

/*Health Controller */
#define off_healthbody 0x20

/*Health Bodypartstate health struct*/
#define off_bodyparthealth 0x10

/*Local GameWorld Offsets*/

#define off_registeredplayers 0x80


/*GameObject Offsets*/

#define off_gameobject_name 0x60
#define off_gameobject_array 0x30
#define off_tag 0x54
#define off_layer 0x50
#define off_isactive 0x57
#define off_isactiveself 0x56
#define off_gameobject_size 0x40


/*Component Offsets*/

#define off_component_monoclass 0x00
#define off_monoclass_name 0x48
#define off_monoclass_namespace 0x50
#define off_component_scripting 0x28

typedef enum
{
    HumanBase = 0,
    HumanPelvis = 14,
    HumanLThigh1 = 15,
    HumanLThigh2 = 16,
    HumanLCalf = 17,
    HumanLFoot = 18,
    HumanLToe = 19,
    HumanRThigh1 = 20,
    HumanRThigh2 = 21,
    HumanRCalf = 22,
    HumanRFoot = 23,
    HumanRToe = 24,
    HumanSpine1 = 29,
    HumanSpine2 = 36,
    HumanSpine3 = 37,
    HumanLCollarbone = 89,
    HumanLUpperarm = 90,
    HumanLForearm1 = 91,
    HumanLForearm2 = 92,
    HumanLForearm3 = 93,
    HumanLPalm = 94,
    HumanRCollarbone = 110,
    HumanRUpperarm = 111,
    HumanRForearm1 = 112,
    HumanRForearm2 = 113,
    HumanRForearm3 = 114,
    HumanRPalm = 115,
    HumanNeck = 132,
    HumanHead = 133
}bones;


#define off_buffers 0x3650
#define off_settings 0x3660
