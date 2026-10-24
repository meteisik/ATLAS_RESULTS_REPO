import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_JadeCipherSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private void applyJadeCipherDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCipher");
        try {
            PreparedStatement jadeCipherDelete = jadeCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeCipherDelete.setString(1, data);
            if (authorized) {
                jadeCipherDelete.executeUpdate();
            }
        } finally {
            jadeCipherConnection.close();
        }
    }

    public void deleteJadeCipherAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("JADE_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyJadeCipherDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
