import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_GoldenCipherSafe {

    private void applyGoldenCipherDeletion(String data, boolean authorized) throws SQLException {
        Connection goldenCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCipher");
        try {
            PreparedStatement goldenCipherDelete = goldenCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenCipherDelete.setString(1, data);
            if (authorized) {
                goldenCipherDelete.executeUpdate();
            }
        } finally {
            goldenCipherConnection.close();
        }
    }

    public void deleteGoldenCipherAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_CIPHER_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyGoldenCipherDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
