import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_SaffronSignal {

    public void deleteSaffronSignalAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_SIGNAL_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_SaffronSignalSink()).applySaffronSignalDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_SaffronSignalSink {
    public void applySaffronSignalDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection saffronSignalConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronSignal");
        try {
            PreparedStatement saffronSignalDelete = saffronSignalConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronSignalDelete.setString(1, data);
            if (authorized) {
                saffronSignalDelete.executeUpdate();
            }
        } finally {
            saffronSignalConnection.close();
        }
    }
}
