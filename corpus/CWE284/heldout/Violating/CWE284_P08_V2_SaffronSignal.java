import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_SaffronSignal {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteSaffronSignalAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("SAFFRON_SIGNAL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_SaffronSignalSink()).applySaffronSignalDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_SaffronSignalSink {
    public void applySaffronSignalDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        try {
            PreparedStatement saffronSignalDelete = saffronSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSignalDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                saffronSignalDelete.executeUpdate();
            }
        } finally {
            saffronSignalConnection.close();
        }
    }
}
