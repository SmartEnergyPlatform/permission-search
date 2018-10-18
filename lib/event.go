/*
 * Copyright 2018 InfAI (CC SES)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package lib

import (
	"encoding/json"
	"errors"
	"log"

	"github.com/SmartEnergyPlatform/amqp-wrapper-lib"
)

var conn *amqp_wrapper_lib.Connection

func InitEventHandling() (err error) {
	conn, err = amqp_wrapper_lib.Init(Config.AmqpUrl, append(Config.ResourceList, Config.PermTopic, Config.UserTopic), Config.AmqpReconnectTimeout)
	if err != nil {
		log.Fatal("ERROR: while initializing amqp connection", err)
		return
	}

	log.Println("init permissions handler")
	err = conn.Consume(Config.AmqpConsumerName+"_"+Config.PermTopic, Config.PermTopic, handlePermissionCommand)
	if err != nil {
		log.Fatal("ERROR: while initializing perm consumer", err)
		return
	}

	log.Println("init user handler")
	err = conn.Consume(Config.AmqpConsumerName+"_"+Config.UserTopic, Config.UserTopic, handleUserCommand)
	if err != nil {
		log.Fatal("ERROR: while initializing user consumer", err)
		return
	}

	log.Println("init features handler", Config.ResourceList)
	for _, resource := range Config.ResourceList {
		err = conn.Consume(Config.AmqpConsumerName+"_"+resource, resource, getResourceCommandHandler(resource))
		if err != nil {
			log.Fatal("ERROR: while initializing resource consumer ", resource, " ", err)
			return
		}
	}
	return
}

func handlePermissionCommand(msg []byte) (err error) {
	log.Println(Config.PermTopic, string(msg))
	command := PermCommandMsg{}
	err = json.Unmarshal(msg, &command)
	if err != nil {
		return
	}
	switch command.Command {
	case "PUT":
		if command.User != "" {
			return SetUserRight(command.Kind, command.Resource, command.User, command.Right)
		}
		if command.Group != "" {
			return SetGroupRight(command.Kind, command.Resource, command.Group, command.Right)
		}
	case "DELETE":
		if command.User != "" {
			return DeleteUserRight(command.Kind, command.Resource, command.User)
		}
		if command.Group != "" {
			return DeleteGroupRight(command.Kind, command.Resource, command.Group)
		}
	}
	return errors.New("unable to handle permission command: " + string(msg))
}

func handleUserCommand(msg []byte) (err error) {
	log.Println(Config.UserTopic, string(msg))
	command := UserCommandMsg{}
	err = json.Unmarshal(msg, &command)
	if err != nil {
		return
	}
	switch command.Command {
	case "DELETE":
		if command.Id != "" {
			return DeleteUser(command.Id)
		}
	}
	log.Println("WARNING: unable to handle user command: " + string(msg))
	return nil
}

func getResourceCommandHandler(resourceName string) amqp_wrapper_lib.ConsumerFunc {
	return func(msg []byte) (err error) {
		command := CommandWrapper{}
		err = json.Unmarshal(msg, &command)
		if err != nil {
			return
		}
		switch command.Command {
		case "PUT":
			return UpdateFeatures(resourceName, msg, command)
		case "DELETE":
			return DeleteFeatures(resourceName, command)
		}
		return errors.New("unable to handle command: " + resourceName + " " + string(msg))
	}
}

func sendEvent(topic string, event interface{}) error {
	payload, err := json.Marshal(event)
	if err != nil {
		log.Println("ERROR: event marshaling:", err)
		return err
	}
	log.Println("DEBUG: send amqp event: ", topic, string(payload))
	return conn.Publish(topic, payload)
}
