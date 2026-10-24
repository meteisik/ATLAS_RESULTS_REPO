import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_VelvetCipherSafe {

    public static String data;

    public static boolean authorized;

    public void deleteVelvetCipherAccount() throws SQLException {
        data = System.getenv("VELVET_CIPHER_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_VelvetCipherSafeSink()).applyVelvetCipherDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_VelvetCipherSafeSink {
    public void applyVelvetCipherDeletion() throws SQLException {
        String data = CWE284_P10_V1_VelvetCipherSafe.data;
        boolean authorized = CWE284_P10_V1_VelvetCipherSafe.authorized;
        Connection velvetCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCipher");
        try {
            PreparedStatement velvetCipherDelete = velvetCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCipherDelete.setString(1, data);
            if (authorized) {
                velvetCipherDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            velvetCipherConnection.close();
        }
    }
}
