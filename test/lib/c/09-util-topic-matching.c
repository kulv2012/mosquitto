#include <mosquitto.h>

int main(int argc, char *argv[])
{
	bool match;

	mosquitto_topic_matches_sub("foo/bar", "foo/bar", &match); if(!match) return 1;
	mosquitto_topic_matches_sub("foo/+", "foo/bar", &match); if(!match) return 1;
	mosquitto_topic_matches_sub("foo/+/baz", "foo/bar/baz", &match); if(!match) return 1;

	mosquitto_topic_matches_sub("foo/+/#", "foo/bar/baz", &match); if(!match) return 1;
	mosquitto_topic_matches_sub("#", "foo/bar/baz", &match); if(!match) return 1;

	mosquitto_topic_matches_sub("foo/bar", "foo", &match); if(match) return 1;
	mosquitto_topic_matches_sub("foo/+", "foo/bar/baz", &match); if(match) return 1;
	mosquitto_topic_matches_sub("foo/+/baz", "foo/bar/bar", &match); if(match) return 1;

	mosquitto_topic_matches_sub("foo/+/#", "fo2/bar/baz", &match); if(match) return 1;

	mosquitto_topic_matches_sub("#", "/foo/bar", &match); if(!match) return 1;
	mosquitto_topic_matches_sub("/#", "/foo/bar", &match); if(!match) return 1;
	mosquitto_topic_matches_sub("/#", "foo/bar", &match); if(match) return 1;

	return 0;
}

