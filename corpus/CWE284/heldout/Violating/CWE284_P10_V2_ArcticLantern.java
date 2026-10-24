import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticLantern {

    public static String data;

    public static boolean authorized;

    public void deleteArcticLanternAccount() throws SQLException {
        switch (7) {
        case 7:
            data = System.getenv("ARCTIC_LANTERN_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticLanternSink()).applyArcticLanternDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticLanternSink {
    public void applyArcticLanternDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticLantern.data;
        boolean authorized = CWE284_P10_V2_ArcticLantern.authorized;
        Connection arcticLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLantern");
        try {
            PreparedStatement arcticLanternDelete = arcticLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticLanternDelete.setString(1, data);
            arcticLanternDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticLanternConnection.close();
        }
    }
}
