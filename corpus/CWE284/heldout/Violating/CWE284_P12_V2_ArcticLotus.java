import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_ArcticLotus {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteArcticLotusAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ARCTIC_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_ArcticLotusBase baseObject = new CWE284_P12_V2_ArcticLotusRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_ArcticLotusBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_ArcticLotusRemover extends CWE284_P12_V2_ArcticLotusBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLotus");
        try {
            PreparedStatement arcticLotusDelete = arcticLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticLotusDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticLotusDelete.executeUpdate();
            }
        } finally {
            arcticLotusConnection.close();
        }
    }
}
