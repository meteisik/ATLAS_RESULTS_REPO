import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_JadeCipher {

    private boolean checkJadeCipherAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteJadeCipherAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_CIPHER_ACCOUNT_ID");
        boolean authorized = checkJadeCipherAccess(data);
        Connection jadeCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCipher");
        try {
            PreparedStatement jadeCipherDelete = jadeCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeCipherDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                jadeCipherDelete.executeUpdate();
            }
        } finally {
            jadeCipherConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
