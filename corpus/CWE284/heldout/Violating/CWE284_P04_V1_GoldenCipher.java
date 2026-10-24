import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_GoldenCipher {

    private boolean checkGoldenCipherAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteGoldenCipherAccount() throws SQLException {
        String data;
        data = System.getenv("GOLDEN_CIPHER_ACCOUNT_ID");
        boolean authorized = checkGoldenCipherAccess(data);
        Connection goldenCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:goldenCipher");
        try {
            PreparedStatement goldenCipherDelete = goldenCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            goldenCipherDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                goldenCipherDelete.executeUpdate();
            }
        } finally {
            goldenCipherConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
