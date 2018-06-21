/*
 * Licensed to Metamarkets Group Inc. (Metamarkets) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  Metamarkets licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.metamx.tranquility.security

import com.metamx.common.scala.Logging
import com.twitter.finagle.{http, Service}
import com.twitter.finagle.http.BasicAuth

object BasicAuthClientMaker extends Logging
{
  def wrapBaseClient(
    baseClient: Service[http.Request, http.Response],
    basicAuthUser: String,
    basicAuthPass: String
  ): Service[http.Request, http.Response] = {
    if (basicAuthUser.length > 0 && basicAuthPass.length > 0) {
      log.info("Using BasicAuth.Client...")
      BasicAuth.client(basicAuthUser, basicAuthPass).andThen(baseClient)
    } else {
      log.info("Using client without authentication..")
      baseClient
    }
  }
}
