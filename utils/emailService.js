import nodemailer from 'nodemailer';
import AppError from './appError.js';

class EmailService {
  constructor() {
    this.transport = this.createTransport();
  }

  createTransport() {
    // Production-ready Gmail configuration
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_FROM,
        pass: process.env.GMAIL_APP_PASSWORD, // Gmail App Password
      },
      secure: true,
      port: 465,
      pool: true, // Use connection pooling for better performance
      maxConnections: 5,
      maxMessages: 100,
    });
  }

  async sendEmail(options) {
    try {
      // 1) Define email options
      const mailOptions = {
        from: `${process.env.EMAIL_FROM_NAME || 'WasteNot App'} <${process.env.EMAIL_FROM}>`,
        to: options.email,
        subject: options.subject,
        text: options.message,
        html: options.html,
      };

      // 2) Actually send the email
      const info = await this.transport.sendMail(mailOptions);
      
      console.log('Email sent successfully:', info.messageId);
      return info;
    } catch (error) {
      console.error('Email sending failed:', error);
      throw new AppError('There was an error sending the email. Try again later.', 500);
    }
  }

  async sendWelcomeEmail(user, verificationToken) {
    const verifyURL = `${process.env.CLIENT_URL}/verify-email/${verificationToken}`;
    
    const subject = 'Welcome! Please verify your email address';
    const message = `Welcome to Food Waste Management App, ${user.firstName}!\n\nPlease verify your email address by clicking the link below:\n${verifyURL}\n\nThis link will expire in 24 hours.\n\nIf you didn't create this account, please ignore this email.`;
    
    const html = `
      <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to Food Waste Management!</h1>
        </div>
        
        <div style="padding: 30px; background: #f9f9f9; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-top: 0;">Hi ${user.firstName}!</h2>
          
          <p style="font-size: 16px; margin-bottom: 25px;">
            Thank you for joining our mission to reduce food waste! To get started, please verify your email address.
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verifyURL}" 
               style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 25px; 
                      font-weight: bold; 
                      display: inline-block;
                      transition: transform 0.3s ease;">
              Verify Email Address
            </a>
          </div>
          
          <p style="font-size: 14px; color: #666; margin-top: 25px;">
            <strong>Note:</strong> This verification link will expire in 24 hours.
          </p>
          
          <p style="font-size: 14px; color: #666;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="${verifyURL}" style="color: #667eea; word-break: break-all;">${verifyURL}</a>
          </p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 25px 0;">
          
          <p style="font-size: 12px; color: #999; text-align: center;">
            If you didn't create this account, please ignore this email.<br>
            This email was sent from Food Waste Management App.
          </p>
        </div>
      </div>
    `;

    await this.sendEmail({
      email: user.email,
      subject,
      message,
      html,
    });
  }

  async sendPasswordResetEmail(user, resetToken) {
    const resetURL = `${process.env.CLIENT_URL}/reset-password/${resetToken}`;
    
    const subject = 'Password Reset Request (Valid for 10 minutes)';
    const message = `Hi ${user.firstName},\n\nYou requested a password reset. Please click the link below to reset your password:\n${resetURL}\n\nThis link will expire in 10 minutes for security reasons.\n\nIf you didn't request this, please ignore this email and your password will remain unchanged.`;
    
    const html = `
      <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="background: linear-gradient(135deg, #ff6b6b 0%, #ffa500 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Password Reset Request</h1>
        </div>
        
        <div style="padding: 30px; background: #f9f9f9; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-top: 0;">Hi ${user.firstName}!</h2>
          
          <p style="font-size: 16px; margin-bottom: 25px;">
            We received a request to reset your password. Click the button below to create a new password.
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetURL}" 
               style="background: linear-gradient(135deg, #ff6b6b 0%, #ffa500 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 25px; 
                      font-weight: bold; 
                      display: inline-block;">
              Reset Password
            </a>
          </div>
          
          <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #856404;">
              <strong>⚠️ Security Notice:</strong> This link will expire in 10 minutes for your security.
            </p>
          </div>
          
          <p style="font-size: 14px; color: #666;">
            If the button doesn't work, copy and paste this link into your browser:<br>
            <a href="${resetURL}" style="color: #ff6b6b; word-break: break-all;">${resetURL}</a>
          </p>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 25px 0;">
          
          <p style="font-size: 12px; color: #999; text-align: center;">
            If you didn't request this password reset, please ignore this email.<br>
            Your password will remain unchanged.
          </p>
        </div>
      </div>
    `;

    await this.sendEmail({
      email: user.email,
      subject,
      message,
      html,
    });
  }

  async sendPasswordChangeConfirmation(user) {
    const subject = 'Password Changed Successfully';
    const message = `Hi ${user.firstName},\n\nThis email confirms that your password was successfully changed.\n\nIf you didn't make this change, please contact our support team immediately.\n\nFor your security, you've been logged out of all devices and will need to log in again with your new password.`;
    
    const html = `
      <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="background: linear-gradient(135deg, #00b894 0%, #00cec9 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Password Changed</h1>
        </div>
        
        <div style="padding: 30px; background: #f9f9f9; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-top: 0;">Hi ${user.firstName}!</h2>
          
          <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; font-size: 16px; color: #155724;">
              ✅ Your password has been successfully changed.
            </p>
          </div>
          
          <p style="font-size: 16px;">
            For your security, you've been logged out of all devices. Please log in again with your new password.
          </p>
          
          <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; font-size: 14px; color: #856404;">
              <strong>⚠️ Security Alert:</strong> If you didn't make this change, please contact our support team immediately.
            </p>
          </div>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="${process.env.CLIENT_URL}/login" 
               style="background: linear-gradient(135deg, #00b894 0%, #00cec9 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 25px; 
                      font-weight: bold; 
                      display: inline-block;">
              Login Now
            </a>
          </div>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 25px 0;">
          
          <p style="font-size: 12px; color: #999; text-align: center;">
            This is an automated security notification.<br>
            Food Waste Management App Security Team
          </p>
        </div>
      </div>
    `;

    await this.sendEmail({
      email: user.email,
      subject,
      message,
      html,
    });
  }

  async sendAccountDeactivationEmail(user) {
    const subject = 'Account Deactivated';
    const message = `Hi ${user.firstName},\n\nYour account has been deactivated. If you believe this was done in error, please contact our support team.\n\nThank you for being part of our community.`;
    
    const html = `
      <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
        <div style="background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Account Deactivated</h1>
        </div>
        
        <div style="padding: 30px; background: #f9f9f9; border-radius: 0 0 10px 10px;">
          <h2 style="color: #333; margin-top: 0;">Hi ${user.firstName}!</h2>
          
          <p style="font-size: 16px; margin-bottom: 25px;">
            Your account has been deactivated. You will no longer be able to access your account or use our services.
          </p>
          
          <p style="font-size: 16px; margin-bottom: 25px;">
            If you believe this was done in error or have any questions, please contact our support team.
          </p>
          
          <div style="text-align: center; margin: 30px 0;">
            <a href="mailto:${process.env.EMAIL_FROM}" 
               style="background: linear-gradient(135deg, #6c5ce7 0%, #a29bfe 100%); 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 25px; 
                      font-weight: bold; 
                      display: inline-block;">
              Contact Support
            </a>
          </div>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 25px 0;">
          
          <p style="font-size: 12px; color: #999; text-align: center;">
            Thank you for being part of our community.<br>
            Food Waste Management App Team
          </p>
        </div>
      </div>
    `;

    await this.sendEmail({
      email: user.email,
      subject,
      message,
      html,
    });
  }

  // Test email connection
  async testConnection() {
    try {
      await this.transport.verify();
      console.log('✅ Email service is ready to send emails');
      return true;
    } catch (error) {
      console.error('❌ Email service configuration error:', error);
      return false;
    }
  }

  // Close transporter connection
  close() {
    this.transport.close();
  }
}

// Create singleton instance
const emailService = new EmailService();

export default emailService;