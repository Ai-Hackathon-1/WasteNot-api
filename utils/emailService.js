import nodemailer from 'nodemailer';
import AppError from './appError.js';

/**
 * Email service class for handling all email operations
 */
class EmailService {
  constructor() {
    this.transport = this.createTransport();
  }

  /**
   * Create nodemailer transporter based on environment
   * @returns {Object} Nodemailer transporter
   */
  createTransport() {
    // For production, use a real SMTP service
    if (process.env.NODE_ENV === 'production') {
      return nodemailer.createTransport({
        service: process.env.EMAIL_SERVICE || 'gmail', // gmail, outlook, etc.
        auth: {
          user: process.env.EMAIL_USERNAME,
          pass: process.env.EMAIL_PASSWORD, // Use app password for Gmail
        },
        secure: true,
        port: 465,
      });
    }

    // For development, you can use Ethereal Email (temporary testing emails)
    // Or configure your preferred SMTP settings
    return nodemailer.createTransport({
      host: process.env.EMAIL_HOST || 'gmail',
      port: process.env.EMAIL_PORT || 587,
      secure: false, // true for 465, false for other ports
      auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
      },
    });
  }

  /**
   * Send email verification email
   * @param {string} to - Recipient email address
   * @param {string} name - Recipient name
   * @param {string} verificationToken - Email verification token
   * @param {string} baseUrl - Base URL of the application
   */
  async sendVerificationEmail(to, name, verificationToken, baseUrl) {
    const verificationUrl = `${baseUrl}/api/auth/verify-email/${verificationToken}`;
    
    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME || 'WasteNot App'}" <${process.env.EMAIL_FROM || process.env.EMAIL_USERNAME}>`,
      to,
      subject: 'Email Verification - WasteNot App',
      html: this.getVerificationEmailTemplate(name, verificationUrl),
      text: `Hi ${name},\n\nPlease verify your email by clicking the following link:\n${verificationUrl}\n\nThis link will expire in 24 hours.\n\nIf you didn't create an account, please ignore this email.\n\nBest regards,\nWasteNot Team`,
    };

    try {
      const info = await this.transport.sendMail(mailOptions);
      console.log('Verification email sent: %s', info.messageId);
      
      // For development with Ethereal, log the preview URL
      if (process.env.NODE_ENV !== 'production') {
        console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
      }
      
      return info;
    } catch (error) {
      console.error('Error sending verification email:', error);
      throw new AppError('Error sending verification email. Please try again later.', 500);
    }
  }

  /**
   * Send password reset email
   * @param {string} to - Recipient email address
   * @param {string} name - Recipient name
   * @param {string} resetToken - Password reset token
   * @param {string} baseUrl - Base URL of the application
   */
  async sendPasswordResetEmail(to, name, resetToken, baseUrl) {
    const resetUrl = `${baseUrl}/api/auth/reset-password/${resetToken}`;
    
    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME || 'WasteNot App'}" <${process.env.EMAIL_FROM || process.env.EMAIL_USERNAME}>`,
      to,
      subject: 'Password Reset Request - WasteNot App',
      html: this.getPasswordResetEmailTemplate(name, resetUrl),
      text: `Hi ${name},\n\nYou requested a password reset. Click the following link to reset your password:\n${resetUrl}\n\nThis link will expire in 10 minutes.\n\nIf you didn't request this, please ignore this email.\n\nBest regards,\nWasteNot Team`,
    };

    try {
      const info = await this.transport.sendMail(mailOptions);
      console.log('Password reset email sent: %s', info.messageId);
      return info;
    } catch (error) {
      console.error('Error sending password reset email:', error);
      throw new AppError('Error sending password reset email. Please try again later.', 500);
    }
  }

  /**
   * Send welcome email after successful verification
   * @param {string} to - Recipient email address
   * @param {string} name - Recipient name
   */
  async sendWelcomeEmail(to, name) {
    const mailOptions = {
      from: `"${process.env.EMAIL_FROM_NAME || 'WasteNot App'}" <${process.env.EMAIL_FROM || process.env.EMAIL_USERNAME}>`,
      to,
      subject: 'Welcome to WasteNot App!',
      html: this.getWelcomeEmailTemplate(name),
      text: `Hi ${name},\n\nWelcome to WasteNot App! Your email has been successfully verified.\n\nYou can now enjoy all the features of our platform.\n\nBest regards,\nWasteNot Team`,
    };

    try {
      const info = await this.transport.sendMail(mailOptions);
      console.log('Welcome email sent: %s', info.messageId);
      return info;
    } catch (error) {
      console.error('Error sending welcome email:', error);
      // Don't throw error for welcome email as it's not critical
      return null;
    }
  }

  /**
   * HTML template for email verification
   * @param {string} name - User name
   * @param {string} verificationUrl - Verification URL
   * @returns {string} HTML template
   */
  getVerificationEmailTemplate(name, verificationUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background-color: #f9f9f9; }
          .button { display: inline-block; padding: 12px 24px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Email Verification</h1>
          </div>
          <div class="content">
            <h2>Hi ${name}!</h2>
            <p>Thank you for registering with WasteNot App. To complete your registration, please verify your email address by clicking the button below:</p>
            <div style="text-align: center;">
              <a href="${verificationUrl}" class="button">Verify Email Address</a>
            </div>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #666;">${verificationUrl}</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
            <p>If you didn't create an account with us, please ignore this email.</p>
          </div>
          <div class="footer">
            <p>Best regards,<br>The WasteNot Team</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * HTML template for password reset
   * @param {string} name - User name
   * @param {string} resetUrl - Password reset URL
   * @returns {string} HTML template
   */
  getPasswordResetEmailTemplate(name, resetUrl) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #FF6B6B; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background-color: #f9f9f9; }
          .button { display: inline-block; padding: 12px 24px; background-color: #FF6B6B; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Password Reset Request</h1>
          </div>
          <div class="content">
            <h2>Hi ${name}!</h2>
            <p>You requested a password reset for your WasteNot App account. Click the button below to reset your password:</p>
            <div style="text-align: center;">
              <a href="${resetUrl}" class="button">Reset Password</a>
            </div>
            <p>Or copy and paste this link in your browser:</p>
            <p style="word-break: break-all; color: #666;">${resetUrl}</p>
            <p><strong>This link will expire in 10 minutes for security reasons.</strong></p>
            <p>If you didn't request this password reset, please ignore this email. Your password will remain unchanged.</p>
          </div>
          <div class="footer">
            <p>Best regards,<br>The WasteNot Team</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * HTML template for welcome email
   * @param {string} name - User name
   * @returns {string} HTML template
   */
  getWelcomeEmailTemplate(name) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to WasteNot App</title>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
          .content { padding: 30px; background-color: #f9f9f9; }
          .footer { text-align: center; padding: 20px; font-size: 12px; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to WasteNot App!</h1>
          </div>
          <div class="content">
            <h2>Hi ${name}!</h2>
            <p>Your email has been successfully verified and your account is now active!</p>
            <p>You can now enjoy all the features of WasteNot App:</p>
            <ul>
              <li>Track your waste reduction progress</li>
              <li>Discover eco-friendly alternatives</li>
              <li>Connect with like-minded individuals</li>
              <li>Access exclusive sustainability tips</li>
            </ul>
            <p>Thank you for joining our mission to reduce waste and protect our planet!</p>
          </div>
          <div class="footer">
            <p>Best regards,<br>The WasteNot Team</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  /**
   * Test email configuration
   * @returns {boolean} True if configuration is valid
   */
  async testConnection() {
    try {
      await this.transport.verify();
      console.log('SMTP configuration is valid');
      return true;
    } catch (error) {
      console.error('SMTP configuration error:', error);
      return false;
    }
  }
}

// Create and export a singleton instance
const emailService = new EmailService();

export default emailService;