import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronCipher {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronCipherAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_CIPHER_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronCipherSink()).applySaffronCipherDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronCipherSink {
    public void applySaffronCipherDeletion(CWE284_P09_V1_SaffronCipher.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        try {
            PreparedStatement saffronCipherDelete = saffronCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCipherDelete.setString(1, data);
            saffronCipherDelete.executeUpdate();
        } finally {
            saffronCipherConnection.close();
        }
    }
}
