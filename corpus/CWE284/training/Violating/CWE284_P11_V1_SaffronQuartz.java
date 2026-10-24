import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_SaffronQuartz {

    public void deleteSaffronQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_QUARTZ_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_SaffronQuartzSink()).applySaffronQuartzDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_SaffronQuartzSink {
    public void applySaffronQuartzDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection saffronQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronQuartz");
        try {
            PreparedStatement saffronQuartzDelete = saffronQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronQuartzDelete.setString(1, data);
            if (authorized) {
                saffronQuartzDelete.executeUpdate();
            }
        } finally {
            saffronQuartzConnection.close();
        }
    }
}
