import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_JadeCipherSafe {

    public void deleteJadeCipherAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_CIPHER_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_JadeCipherSafeSink()).applyJadeCipherDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_JadeCipherSafeSink {
    public void applyJadeCipherDeletion(String data, boolean authorized) throws SQLException {
        Connection jadeCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeCipher");
        try {
            PreparedStatement jadeCipherDelete = jadeCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeCipherDelete.setString(1, data);
            if (authorized) {
                jadeCipherDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            jadeCipherConnection.close();
        }
    }
}
