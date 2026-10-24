import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_MosaicNebula {

    private String mosaicNebulaAccountId;

    private boolean mosaicNebulaAuthorized;

    private void applyMosaicNebulaDeletion() throws SQLException {
        String data = mosaicNebulaAccountId;
        boolean authorized = mosaicNebulaAuthorized;
        Connection mosaicNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicNebula");
        try {
            PreparedStatement mosaicNebulaDelete = mosaicNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            mosaicNebulaDelete.setString(1, data);
            mosaicNebulaDelete.executeUpdate();
        } finally {
            mosaicNebulaConnection.close();
        }
    }

    public void deleteMosaicNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("MOSAIC_NEBULA_ACCOUNT_ID");
        mosaicNebulaAccountId = data;
        mosaicNebulaAuthorized = isAuthorized(data);
        applyMosaicNebulaDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
