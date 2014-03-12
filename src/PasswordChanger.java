import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/**
 * Provide passwords created by using java.security.MessageDigest and a salt that matches with
 * org.springframework.security.authentication.encoding.PasswordEncoder
 * 
 * @author nicomartin.enego
 */
public class PasswordChanger {

	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		String salt, newPass, algorithm, generatedPassword, answer;
		Scanner a = new Scanner(System.in);
		System.out.println("Password Changer Tool for Spring Security");

		while (true) {
			// get Hashing algorithm
			System.out.print("Input hash algorithm (default: SHA-1): ");
			algorithm = a.nextLine();
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance(algorithm);
			} catch (NoSuchAlgorithmException e) {
				// e.printStackTrace();
				System.out.println("No algorithm found, defaulting to SHA-1");
				algorithm = "SHA-1";
				md = MessageDigest.getInstance(algorithm);
			}

			// get password and salt
			System.out.print("Enter new password: ");
			newPass = a.nextLine();
			System.out.print("Enter salt (default: random): ");
			salt = a.nextLine();

			if (salt.isEmpty()) {
				// if no salt is provided, generate random salt for our lazy user.
				salt = getSalt();
				System.out.println("Generated random salt: " + salt);
			}

			// we perform the hashing..
			String saltedPass = mergePasswordAndSalt(newPass, salt, true);
			byte[] bytes = md.digest(saltedPass.getBytes("UTF-8"));
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
			}
			generatedPassword = sb.toString();

			// viola.
			System.out.println("=========== RESULTS ===========");
			System.out.println("Hash algorithm: " + algorithm);
			System.out.println("Password: " + newPass);
			System.out.println("Salt: " + salt);
			System.out.println("Hashed password: " + generatedPassword);

			System.out.println("");
			System.out.println("Some more? (Y/n)");

			answer = a.nextLine();
			if (!(answer.equals("y") || answer.equals("Y"))) {
				System.out.println("Goodbye.");
				break;
			}
		}

	}

	/**
	 * Generate random salt.
	 * From: http://howtodoinjava.com/2013/07/22/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
	 * 
	 * @return random salt
	 * @throws NoSuchAlgorithmException
	 */
	public static String getSalt() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt.toString();
	}

	/**
	 * From org.springframework.security.authentication.encoding.BasePasswordEncoder:
	 * Used by subclasses to generate a merged password and salt <code>String</code>.
	 * <P>
	 * The generated password will be in the form of <code>password{salt}</code>.
	 * </p>
	 * <p>
	 * A <code>null</code> can be passed to either method, and will be handled correctly. If the <code>salt</code> is <code>null</code> or empty, the
	 * resulting generated password will simply be the passed <code>password</code>. The <code>toString</code> method of the <code>salt</code> will be
	 * used to represent the salt.
	 * </p>
	 * 
	 * @param password the password to be used (can be <code>null</code>)
	 * @param salt the salt to be used (can be <code>null</code>)
	 * @param strict ensures salt doesn't contain the delimiters
	 * @return a merged password and salt <code>String</code>
	 * @throws IllegalArgumentException if the salt contains '{' or '}' characters.
	 */
	public static String mergePasswordAndSalt(String password, Object salt, boolean strict) {
		if (password == null) {
			password = "";
		}

		if (strict && (salt != null)) {
			if ((salt.toString().lastIndexOf("{") != -1) || (salt.toString().lastIndexOf("}") != -1)) {
				throw new IllegalArgumentException("Cannot use { or } in salt.toString()");
			}
		}

		if ((salt == null) || "".equals(salt)) {
			return password;
		} else {
			return password + "{" + salt.toString() + "}";
		}
	}
}
