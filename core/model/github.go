// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

// WebhookRequest is the request from github webhook
type WebhookRequest struct {
	Ref     string   `json:"ref"`
	Before  string   `json:"before"`
	After   string   `json:"after"`
	Created bool     `json:"created"`
	Deleted bool     `json:"deleted"`
	Forced  bool     `json:"forced"`
	BaseRef string   `json:"base_ref"`
	Compare string   `json:"compare"`
	Commits []Commit `json:"commits"`
}

// Commit is the commit information of github push events
type Commit struct {
	ID        string    `json:"id"`
	TreeID    string    `json:"tree_id"`
	Distinct  bool      `json:"distinct"`
	Message   string    `json:"message"`
	Timestamp string    `json:"timestamp"`
	URL       string    `json:"url"`
	Author    Author    `json:"author"`
	Committer Committer `json:"committer"`
	Added     []string  `json:"added"`
	Removed   []string  `json:"removed"`
	Modified  []string  `json:"modified"`
}

// AppConfigFile is the file information in a commit of github push event
type AppConfigFile struct {
	Name     string `json:"name"`
	IsDelete bool   `json:"is_delete"`
}
