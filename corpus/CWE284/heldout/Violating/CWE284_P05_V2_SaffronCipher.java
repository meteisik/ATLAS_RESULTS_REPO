import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_SaffronCipher {
    private static int privateFive = 5;

    private String saffronCipherAccountId;

    private boolean saffronCipherAuthorized;

    private void applySaffronCipherDeletion() throws SQLException {
        String data = saffronCipherAccountId;
        boolean authorized = saffronCipherAuthorized;
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        try {
            PreparedStatement saffronCipherDelete = saffronCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCipherDelete.setString(1, data);
            saffronCipherDelete.executeUpdate();
        } finally {
            saffronCipherConnection.close();
        }
    }

    public void deleteSaffronCipherAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SAFFRON_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        saffronCipherAccountId = data;
        saffronCipherAuthorized = isAuthorized(data);
        applySaffronCipherDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
