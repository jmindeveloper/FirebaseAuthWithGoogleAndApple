//
//  ViewController.swift
//  FirebaseLoginWithGoogleAndApple
//
//  Created by J_Min on 2022/12/17.
//

import UIKit
import FirebaseAuth
import GoogleSignIn
import FirebaseCore

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    @IBAction func googleLogin(_ sender: UIButton) {
        FirebaseAuth.shared.signInWithGoogle(vc: self)
    }
    
    @IBAction func appleLogin(_ sender: UIButton) {
        FirebaseAuth.shared.signInWithApple(window: UIApplication.shared.keyWindow!)
    }
    
    @IBAction func getUserInfo(_ sender: UIButton) {
        guard let user = Auth.auth().currentUser else {
            print("user is nill")
            return
        }
        
        print(user.displayName, user.uid)
    }
    
    @IBAction func logout(_ sender: UIButton) {
        do {
            try Auth.auth().signOut()
            GIDSignIn.sharedInstance.signOut()
        } catch {
            print("logout error, \(error.localizedDescription)")
        }
    }

}

