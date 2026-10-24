import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_ArcticLantern {

    public void deleteArcticLanternAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("ARCTIC_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_ArcticLanternBase baseObject = new CWE284_P12_V2_ArcticLanternRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_ArcticLanternBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_ArcticLanternRemover extends CWE284_P12_V2_ArcticLanternBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLantern");
        try {
            PreparedStatement arcticLanternDelete = arcticLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticLanternDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticLanternDelete.executeUpdate();
            }
        } finally {
            arcticLanternConnection.close();
        }
    }
}
