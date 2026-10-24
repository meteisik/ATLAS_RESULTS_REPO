import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_SaffronCipherSafe {

    public void deleteSaffronCipherAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_CIPHER_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_SaffronCipherSafeSink()).applySaffronCipherDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_SaffronCipherSafeSink {
    public void applySaffronCipherDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection saffronCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCipher");
        try {
            PreparedStatement saffronCipherDelete = saffronCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCipherDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                saffronCipherDelete.executeUpdate();
            }
        } finally {
            saffronCipherConnection.close();
        }
    }
}
