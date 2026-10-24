import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_SaffronQuartzSafe {

    public void deleteSaffronQuartzAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("SAFFRON_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_SaffronQuartzSafeSink()).applySaffronQuartzDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_SaffronQuartzSafeSink {
    public void applySaffronQuartzDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection saffronQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronQuartz");
        try {
            PreparedStatement saffronQuartzDelete = saffronQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronQuartzDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                saffronQuartzDelete.executeUpdate();
            }
        } finally {
            saffronQuartzConnection.close();
        }
    }
}
