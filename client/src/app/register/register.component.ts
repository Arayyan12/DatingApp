import { Component, Input, OnInit, Output, EventEmitter } from '@angular/core';
import { AccountService } from '../_Services/account.service';


@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
  model: any = {};
  @Output() canselRegister = new EventEmitter();

  constructor(private accountService: AccountService) { }

  ngOnInit(): void {
  }
  register() {
    this.accountService.register(this.model).subscribe(response => {
      console.log(response);
      this.cancel();
    },error=>{
      console.log(error);
    })
  }
  cancel() {
    console.log("cancelled");
    this.canselRegister.emit(false);
  }
}
