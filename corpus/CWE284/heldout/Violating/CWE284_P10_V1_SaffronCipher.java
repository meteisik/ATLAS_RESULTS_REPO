import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronCipher {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronCipherAccount() throws SQLException {
        data = System.getenv("SAFFRON_CIPHER_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronCipherSink()).applySaffronCipherDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronCipherSink {
    public void applySaffronCipherDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronCipher.data;
        boolean authorized = CWE284_P10_V1_SaffronCipher.authorized;
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        try {
            PreparedStatement saffronCipherDelete = saffronCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCipherDelete.setString(1, data);
            saffronCipherDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronCipherConnection.close();
        }
    }
}
