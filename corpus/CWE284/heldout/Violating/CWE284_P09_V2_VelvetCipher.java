import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VelvetCipher {
    private static boolean privateTrue = true;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVelvetCipherAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("VELVET_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VelvetCipherSink()).applyVelvetCipherDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VelvetCipherSink {
    public void applyVelvetCipherDeletion(CWE284_P09_V2_VelvetCipher.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection velvetCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCipher");
        try {
            PreparedStatement velvetCipherDelete = velvetCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCipherDelete.setString(1, data);
            velvetCipherDelete.executeUpdate();
        } finally {
            velvetCipherConnection.close();
        }
    }
}
