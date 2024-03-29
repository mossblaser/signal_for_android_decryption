# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: Backups.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\rBackups.proto\x12\x06signal\"\xe2\x01\n\x0cSqlStatement\x12\x11\n\tstatement\x18\x01 \x01(\t\x12\x35\n\nparameters\x18\x02 \x03(\x0b\x32!.signal.SqlStatement.SqlParameter\x1a\x87\x01\n\x0cSqlParameter\x12\x16\n\x0estringParamter\x18\x01 \x01(\t\x12\x18\n\x10integerParameter\x18\x02 \x01(\x04\x12\x17\n\x0f\x64oubleParameter\x18\x03 \x01(\x01\x12\x15\n\rblobParameter\x18\x04 \x01(\x0c\x12\x15\n\rnullparameter\x18\x05 \x01(\x08\"\x84\x01\n\x10SharedPreference\x12\x0c\n\x04\x66ile\x18\x01 \x01(\t\x12\x0b\n\x03key\x18\x02 \x01(\t\x12\r\n\x05value\x18\x03 \x01(\t\x12\x14\n\x0c\x62ooleanValue\x18\x04 \x01(\x08\x12\x16\n\x0estringSetValue\x18\x05 \x03(\t\x12\x18\n\x10isStringSetValue\x18\x06 \x01(\x08\"A\n\nAttachment\x12\r\n\x05rowId\x18\x01 \x01(\x04\x12\x14\n\x0c\x61ttachmentId\x18\x02 \x01(\x04\x12\x0e\n\x06length\x18\x03 \x01(\r\"(\n\x07Sticker\x12\r\n\x05rowId\x18\x01 \x01(\x04\x12\x0e\n\x06length\x18\x02 \x01(\r\";\n\x06\x41vatar\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x13\n\x0brecipientId\x18\x03 \x01(\t\x12\x0e\n\x06length\x18\x02 \x01(\r\"\"\n\x0f\x44\x61tabaseVersion\x12\x0f\n\x07version\x18\x01 \x01(\r\"3\n\x06Header\x12\n\n\x02iv\x18\x01 \x01(\x0c\x12\x0c\n\x04salt\x18\x02 \x01(\x0c\x12\x0f\n\x07version\x18\x03 \x01(\r\"\x92\x01\n\x08KeyValue\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x11\n\tblobValue\x18\x02 \x01(\x0c\x12\x14\n\x0c\x62ooleanValue\x18\x03 \x01(\x08\x12\x12\n\nfloatValue\x18\x04 \x01(\x02\x12\x14\n\x0cintegerValue\x18\x05 \x01(\x05\x12\x11\n\tlongValue\x18\x06 \x01(\x03\x12\x13\n\x0bstringValue\x18\x07 \x01(\t\"\xc9\x02\n\x0b\x42\x61\x63kupFrame\x12\x1e\n\x06header\x18\x01 \x01(\x0b\x32\x0e.signal.Header\x12\'\n\tstatement\x18\x02 \x01(\x0b\x32\x14.signal.SqlStatement\x12,\n\npreference\x18\x03 \x01(\x0b\x32\x18.signal.SharedPreference\x12&\n\nattachment\x18\x04 \x01(\x0b\x32\x12.signal.Attachment\x12(\n\x07version\x18\x05 \x01(\x0b\x32\x17.signal.DatabaseVersion\x12\x0b\n\x03\x65nd\x18\x06 \x01(\x08\x12\x1e\n\x06\x61vatar\x18\x07 \x01(\x0b\x32\x0e.signal.Avatar\x12 \n\x07sticker\x18\x08 \x01(\x0b\x32\x0f.signal.Sticker\x12\"\n\x08keyValue\x18\t \x01(\x0b\x32\x10.signal.KeyValueB)\n\'org.thoughtcrime.securesms.backup.proto')



_SQLSTATEMENT = DESCRIPTOR.message_types_by_name['SqlStatement']
_SQLSTATEMENT_SQLPARAMETER = _SQLSTATEMENT.nested_types_by_name['SqlParameter']
_SHAREDPREFERENCE = DESCRIPTOR.message_types_by_name['SharedPreference']
_ATTACHMENT = DESCRIPTOR.message_types_by_name['Attachment']
_STICKER = DESCRIPTOR.message_types_by_name['Sticker']
_AVATAR = DESCRIPTOR.message_types_by_name['Avatar']
_DATABASEVERSION = DESCRIPTOR.message_types_by_name['DatabaseVersion']
_HEADER = DESCRIPTOR.message_types_by_name['Header']
_KEYVALUE = DESCRIPTOR.message_types_by_name['KeyValue']
_BACKUPFRAME = DESCRIPTOR.message_types_by_name['BackupFrame']
SqlStatement = _reflection.GeneratedProtocolMessageType('SqlStatement', (_message.Message,), {

  'SqlParameter' : _reflection.GeneratedProtocolMessageType('SqlParameter', (_message.Message,), {
    'DESCRIPTOR' : _SQLSTATEMENT_SQLPARAMETER,
    '__module__' : 'Backups_pb2'
    # @@protoc_insertion_point(class_scope:signal.SqlStatement.SqlParameter)
    })
  ,
  'DESCRIPTOR' : _SQLSTATEMENT,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.SqlStatement)
  })
_sym_db.RegisterMessage(SqlStatement)
_sym_db.RegisterMessage(SqlStatement.SqlParameter)

SharedPreference = _reflection.GeneratedProtocolMessageType('SharedPreference', (_message.Message,), {
  'DESCRIPTOR' : _SHAREDPREFERENCE,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.SharedPreference)
  })
_sym_db.RegisterMessage(SharedPreference)

Attachment = _reflection.GeneratedProtocolMessageType('Attachment', (_message.Message,), {
  'DESCRIPTOR' : _ATTACHMENT,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.Attachment)
  })
_sym_db.RegisterMessage(Attachment)

Sticker = _reflection.GeneratedProtocolMessageType('Sticker', (_message.Message,), {
  'DESCRIPTOR' : _STICKER,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.Sticker)
  })
_sym_db.RegisterMessage(Sticker)

Avatar = _reflection.GeneratedProtocolMessageType('Avatar', (_message.Message,), {
  'DESCRIPTOR' : _AVATAR,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.Avatar)
  })
_sym_db.RegisterMessage(Avatar)

DatabaseVersion = _reflection.GeneratedProtocolMessageType('DatabaseVersion', (_message.Message,), {
  'DESCRIPTOR' : _DATABASEVERSION,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.DatabaseVersion)
  })
_sym_db.RegisterMessage(DatabaseVersion)

Header = _reflection.GeneratedProtocolMessageType('Header', (_message.Message,), {
  'DESCRIPTOR' : _HEADER,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.Header)
  })
_sym_db.RegisterMessage(Header)

KeyValue = _reflection.GeneratedProtocolMessageType('KeyValue', (_message.Message,), {
  'DESCRIPTOR' : _KEYVALUE,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.KeyValue)
  })
_sym_db.RegisterMessage(KeyValue)

BackupFrame = _reflection.GeneratedProtocolMessageType('BackupFrame', (_message.Message,), {
  'DESCRIPTOR' : _BACKUPFRAME,
  '__module__' : 'Backups_pb2'
  # @@protoc_insertion_point(class_scope:signal.BackupFrame)
  })
_sym_db.RegisterMessage(BackupFrame)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'\n\'org.thoughtcrime.securesms.backup.proto'
  _SQLSTATEMENT._serialized_start=26
  _SQLSTATEMENT._serialized_end=252
  _SQLSTATEMENT_SQLPARAMETER._serialized_start=117
  _SQLSTATEMENT_SQLPARAMETER._serialized_end=252
  _SHAREDPREFERENCE._serialized_start=255
  _SHAREDPREFERENCE._serialized_end=387
  _ATTACHMENT._serialized_start=389
  _ATTACHMENT._serialized_end=454
  _STICKER._serialized_start=456
  _STICKER._serialized_end=496
  _AVATAR._serialized_start=498
  _AVATAR._serialized_end=557
  _DATABASEVERSION._serialized_start=559
  _DATABASEVERSION._serialized_end=593
  _HEADER._serialized_start=595
  _HEADER._serialized_end=646
  _KEYVALUE._serialized_start=649
  _KEYVALUE._serialized_end=795
  _BACKUPFRAME._serialized_start=798
  _BACKUPFRAME._serialized_end=1127
# @@protoc_insertion_point(module_scope)
