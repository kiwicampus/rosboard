from rosidl_adapter.parser import parse_message_string
from rosidl_runtime_py import get_interface_path

from rosboard.ros_init import rospy

def get_all_topics():
    all_topics = {}
    for topic_tuple in rospy.get_published_topics():
        topic_name = topic_tuple[0]
        topic_type = topic_tuple[1]
        if type(topic_type) is list:
            topic_type = topic_type[0] # ROS2
        all_topics[topic_name] = topic_type
    return all_topics

def get_all_topics_with_typedef():
    topics = get_all_topics()
    full_topics = {}
    for topic_name, topic_type in topics.items():
        full_typedef = get_typedef_full_text(topic_type)
        full_topics[topic_name] = {"type": topic_type, "typedef": full_typedef}
    return full_topics

def get_typedef_full_text(ty):
    """Returns the full text (similar to `gendeps --cat`) for the specified message type"""
    try:
        return stringify_field_types(ty)
    except Exception as e:
        return f"# failed to get full definition text for {ty}: {str(e)}"
    
# Taken from https://github.com/RobotWebTools/rosbridge_suite/blob/7d78af16d30d0ffe232abcc65d0928ce90bd61f7/rosapi/src/rosapi/stringify_field_types.py#L5
def stringify_field_types(root_type):
    definition = ""
    seen_types = set()
    deps = [root_type]
    is_root = True
    while deps:
        ty = deps.pop()
        parts = ty.split("/")
        if not is_root:
            definition += "\n================================================================================\n"
            definition += f"MSG: {ty}\n"
        is_root = False

        msg_name = parts[2] if len(parts) == 3 else parts[1]
        interface_name = ty if len(parts) == 3 else f"{parts[0]}/msg/{parts[1]}"
        with open(get_interface_path(interface_name), encoding="utf-8") as msg_file:
            msg_definition = msg_file.read()
        definition += msg_definition

        spec = parse_message_string(parts[0], msg_name, msg_definition)
        for field in spec.fields:
            is_builtin = field.type.pkg_name is None
            if not is_builtin:
                field_ty = f"{field.type.pkg_name}/{field.type.type}"
                if field_ty not in seen_types:
                    deps.append(field_ty)
                    seen_types.add(field_ty)

    return definition
