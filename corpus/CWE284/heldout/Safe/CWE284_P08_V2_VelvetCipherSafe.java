import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VelvetCipherSafe {

    public void deleteVelvetCipherAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("VELVET_CIPHER_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VelvetCipherSafeSink()).applyVelvetCipherDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VelvetCipherSafeSink {
    public void applyVelvetCipherDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection velvetCipherConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCipher");
        try {
            PreparedStatement velvetCipherDelete = velvetCipherConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCipherDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetCipherDelete.executeUpdate();
            }
        } finally {
            velvetCipherConnection.close();
        }
    }
}
