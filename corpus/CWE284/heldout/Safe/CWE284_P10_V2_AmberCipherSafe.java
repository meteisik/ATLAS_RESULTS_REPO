import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberCipherSafe {

    public static String data;

    public static boolean authorized;

    public void deleteAmberCipherAccount() throws SQLException {
        if (true) {
            data = System.getenv("AMBER_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberCipherSafeSink()).applyAmberCipherDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberCipherSafeSink {
    public void applyAmberCipherDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberCipherSafe.data;
        boolean authorized = CWE284_P10_V2_AmberCipherSafe.authorized;
        Connection amberCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCipher");
        try {
            PreparedStatement amberCipherDelete = amberCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberCipherDelete.setString(1, data);
            if (authorized) {
                amberCipherDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberCipherConnection.close();
        }
    }
}
