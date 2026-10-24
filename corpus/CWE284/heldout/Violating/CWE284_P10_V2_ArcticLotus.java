import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticLotus {

    public static String data;

    public static boolean authorized;

    public void deleteArcticLotusAccount() throws SQLException {
        while (true) {
            data = System.getenv("ARCTIC_LOTUS_ACCOUNT_ID");
            break;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticLotusSink()).applyArcticLotusDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticLotusSink {
    public void applyArcticLotusDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticLotus.data;
        boolean authorized = CWE284_P10_V2_ArcticLotus.authorized;
        Connection arcticLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLotus");
        try {
            PreparedStatement arcticLotusDelete = arcticLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticLotusDelete.setString(1, data);
            arcticLotusDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticLotusConnection.close();
        }
    }
}
