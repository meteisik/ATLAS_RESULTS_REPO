import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeCipherSafe {

    private String jadeCipherAccountId;

    private boolean jadeCipherAuthorized;

    private void applyJadeCipherDeletion() throws SQLException {
        String data = jadeCipherAccountId;
        boolean authorized = jadeCipherAuthorized;
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
        data = System.getenv("JADE_CIPHER_ACCOUNT_ID");
        jadeCipherAccountId = data;
        jadeCipherAuthorized = isAuthorized(data);
        applyJadeCipherDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
