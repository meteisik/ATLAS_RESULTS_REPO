import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberQuartz {
    private static int privateFive = 5;

    public static String data;

    public static boolean authorized;

    public void deleteAmberQuartzAccount() throws SQLException {
        if (privateFive == 5) {
            data = System.getenv("AMBER_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberQuartzSink()).applyAmberQuartzDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberQuartzSink {
    public void applyAmberQuartzDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberQuartz.data;
        boolean authorized = CWE284_P10_V2_AmberQuartz.authorized;
        Connection amberQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberQuartz");
        try {
            PreparedStatement amberQuartzDelete = amberQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberQuartzDelete.setString(1, data);
            amberQuartzDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberQuartzConnection.close();
        }
    }
}
