import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  vus: 50, // 50 virtual users
  duration: '5m', // run for 5 minutes
};

export default function () {
  // Replace with your actual LoadBalancer URL once it's up!
  http.get('http://addd8177b04d84ff5a2a495c85f2e1ca-506031512.us-east-1.elb.amazonaws.com/api/products'); 
  sleep(1);
}