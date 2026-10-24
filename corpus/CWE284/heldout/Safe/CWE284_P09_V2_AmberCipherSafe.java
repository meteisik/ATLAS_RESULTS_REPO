import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberCipherSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteAmberCipherAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("AMBER_CIPHER_ACCOUNT_ID");
            break;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberCipherSafeSink()).applyAmberCipherDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberCipherSafeSink {
    public void applyAmberCipherDeletion(CWE284_P09_V2_AmberCipherSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCipher");
        try {
            PreparedStatement amberCipherDelete = amberCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberCipherDelete.setString(1, data);
            if (authorized) {
                amberCipherDelete.executeUpdate();
            }
        } finally {
            amberCipherConnection.close();
        }
    }
}
