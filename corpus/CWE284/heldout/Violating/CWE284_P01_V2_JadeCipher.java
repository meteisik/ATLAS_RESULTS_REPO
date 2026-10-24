import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeCipher {

    public void deleteJadeCipherAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("JADE_CIPHER_ACCOUNT_ID");
            break;
        }
        boolean authorized = isAuthorized(data);
        Connection jadeCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCipher");
        try {
            PreparedStatement jadeCipherDelete = jadeCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeCipherDelete.setString(1, data);
            jadeCipherDelete.executeUpdate();
        } finally {
            jadeCipherConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
