import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V1_SaffronQuartzSafe {

    public static String data;

    public static boolean authorized;

    public void deleteSaffronQuartzAccount() throws SQLException {
        data = System.getenv("SAFFRON_QUARTZ_ACCOUNT_ID");
        authorized = isAuthorized(data);
        (new CWE284_P10_V1_SaffronQuartzSafeSink()).applySaffronQuartzDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V1_SaffronQuartzSafeSink {
    public void applySaffronQuartzDeletion() throws SQLException {
        String data = CWE284_P10_V1_SaffronQuartzSafe.data;
        boolean authorized = CWE284_P10_V1_SaffronQuartzSafe.authorized;
        Connection saffronQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronQuartz");
        try {
            PreparedStatement saffronQuartzDelete = saffronQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronQuartzDelete.setString(1, data);
            if (authorized) {
                saffronQuartzDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronQuartzConnection.close();
        }
    }
}
