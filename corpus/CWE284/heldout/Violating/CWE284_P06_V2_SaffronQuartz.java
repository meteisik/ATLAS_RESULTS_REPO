import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronQuartz {

    public void deleteSaffronQuartzAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("SAFFRON_QUARTZ_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronQuartzSink()).applySaffronQuartzDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronQuartzSink {
    public void applySaffronQuartzDeletion(String data, boolean authorized) throws SQLException {
        Connection saffronQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronQuartz");
        try {
            PreparedStatement saffronQuartzDelete = saffronQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronQuartzDelete.setString(1, data);
            saffronQuartzDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronQuartzConnection.close();
        }
    }
}
