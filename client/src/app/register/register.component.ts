import { Component, Input, OnInit, Output, EventEmitter } from '@angular/core';
import { ToastrService } from 'ngx-toastr';
import { AccountService } from '../_Services/account.service';


@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent implements OnInit {
  model: any = {};
  @Output() canselRegister = new EventEmitter();

  constructor(private accountService: AccountService, private toaster:ToastrService) { }

  ngOnInit(): void {
  }
  register() {
    this.accountService.register(this.model).subscribe(response => {
      console.log(response);
      this.cancel();
    },error=>{
      console.log(error);
      this.toaster.error(error.error);
    })
  }
  cancel() {
    console.log("cancelled");
    this.canselRegister.emit(false);
  }
}
